//
// Created by z742978469 on 20-1-27.
//

#ifndef PEAK_ROOT_SUPPORT_SEARCHVALUE_H
#define PEAK_ROOT_SUPPORT_SEARCHVALUE_H

#include <vector>

typedef enum{
    f64=0, f32, i32, i8, i16, i64, F64=0, F32, I32, I8, I16, I64
} SearchValueType;

typedef union value_t{
    int8_t int8_value;
    int16_t int16_value;
    int32_t int32_value;
    long long int64_value;
    float float32_value;
    double float64_value;
    char bytes[8];
} value_t;

typedef struct value_reg{
    value_t value;
    int32_t offset;
    SearchValueType type;
} value_reg;


class SearchValue{
private:
    size_t sum=0;
    SearchValueType defaultType=i32;
    std::vector<value_reg> valueAll;
    int32_t lastOffset=0;
    int32_t maxlength=0;

public:

    SearchValue(){}

    SearchValue(int32_t value);

    SearchValue(std::vector<value_reg>& value,int32_t maxLength);

    void set(std::vector<value_reg>& value,int32_t maxLength);

    template <typename T>
    SearchValue(T value,SearchValueType type){
        value_reg tmp;
        defaultType=type;
        tmp.type=type;
        tmp.offset=0;
        switch (type){
            case i8:
                tmp.value.int8_value=value;
                sum++;
                maxlength=1;
                break;
            case i16:
                tmp.value.int16_value=value;
                sum++;
                maxlength=2;
                break;
            case i32:
                tmp.value.int32_value=value;
                sum++;
                maxlength=4;
                break;
            case i64:
                tmp.value.int64_value=value;
                sum++;
                maxlength=8;
                break;
            case f32:
                tmp.value.float32_value=value;
                sum++;
                maxlength=4;
                break;
            case f64:
                tmp.value.float64_value=value;
                sum++;
                maxlength=8;
                break;
            default:
                break;
        }
        valueAll.push_back(tmp);
    }

    template <typename T>
    bool append(T value,SearchValueType type,unsigned int offset){
        value_reg tmp;
        tmp.type=type;
        tmp.offset=offset-lastOffset;
        lastOffset=offset;
        int32_t lengthTemp;
        switch (type){
            case i8:
                tmp.value.int8_value=value;
                lengthTemp=offset+1;
                if(lengthTemp>maxlength) {
                    maxlength=lengthTemp;
                }
                break;
            case i16:
                tmp.value.int16_value=value;
                lengthTemp=offset+2;
                if(lengthTemp>maxlength) {
                    maxlength=lengthTemp;
                }
                break;
            case i32:
                tmp.value.int32_value=value;
                lengthTemp=offset+4;
                if(lengthTemp>maxlength) {
                    maxlength=lengthTemp;
                }
                break;
            case i64:
                tmp.value.int64_value=value;
                lengthTemp=offset+8;
                if(lengthTemp>maxlength) {
                    maxlength=lengthTemp;
                }
                break;
            case f32:
                tmp.value.float32_value=value;
                lengthTemp=offset+4;
                if(lengthTemp>maxlength) {
                    maxlength=lengthTemp;
                }
                break;
            case f64:
                tmp.value.float64_value=value;
                lengthTemp=offset+8;
                if(lengthTemp>maxlength) {
                    maxlength=lengthTemp;
                }
                break;
            default:
                return false;
        }
        sum++;
        valueAll.push_back(tmp);
        return true;
    }

    template <typename T>
    bool append(T value,unsigned int offset){
        return append(value,defaultType,offset);
    }

    void setDefalutType(SearchValueType type);

    std::vector<value_reg> getValue();

    size_t getNum();

    int32_t getMaxLength();
};


#endif //PEAK_ROOT_SUPPORT_SEARCHVALUE_H
