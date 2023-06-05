import { RegisterDto } from "../dto/register.dto";

export interface RegisterResponse{

    user : RegisterDto,
    token : string
}