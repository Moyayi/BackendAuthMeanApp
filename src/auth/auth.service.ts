import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';

import { CreateUserDto } from './dto/create-user.dto';

import * as bcryptjs from 'bcryptjs'

import { UpdateAuthDto } from './dto/update-user.dto';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './entities/user.entity';
import { Model } from 'mongoose';
import { LoginDto } from './dto/login.dto';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload';

@Injectable()
export class AuthService {

  
  constructor(
    @InjectModel( User.name) 
    private userModel : Model<User>,
    private jwtService : JwtService
  ){}

  async create(createUserDto: CreateUserDto) : Promise<User> {
    try{
      const { password, ...userData } = createUserDto;

      const newUser = new this.userModel( 
        {
          password : bcryptjs.hashSync( password, 10),
          ...userData
        }
        );

      // Encriptar contraseña
      // Guardar el usuario
      // Generar el JWT

      await newUser.save();
      const { password:_, ...user} = newUser.toJSON();

      return user;

    }catch( error ){
      if(error.code === 11000){
        throw new BadRequestException(`${ createUserDto.email } ya existe el correo`)
      }
      throw new InternalServerErrorException('Error desconocido')
    }
  }

  async login( loginDto : LoginDto ){
    const {email, password} = loginDto;

    const user = await this.userModel.findOne({ email })


    console.log(user)

    if( !user ){
      throw new UnauthorizedException('Credenciales erroneas - email')
    }
    
    if ( !bcryptjs.compareSync( password, user.password )){
      throw new UnauthorizedException('Credenciales erroneas - password')
    }


    const  { password:_, ...dataUser} = user.toJSON();
    
    return {
      user : dataUser,
      token: this.getJwtToken({ id : user.id })
    }

  }

  findAll() {
    return `This action returns all auth`;
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }

  getJwtToken ( payload : JwtPayload ){
    const token = this.jwtService.sign(payload)
    return token;
  }

}