//
// Created by z742978469 on 20-1-27.
//

#include <cstdint>

#include "SearchValue.h"

SearchValue::SearchValue(int32_t value){
    value_reg tmp;
    tmp.type=i32;
    tmp.offset=0;
    tmp.value.int32_value=value;
    maxlength=4;
    sum++;
    valueAll.push_back(tmp);
}

SearchValue::SearchValue(std::vector<value_reg>& value,int32_t maxLength){
    valueAll= value;
    this->maxlength=maxLength;
    this->sum=valueAll.size();
}

void SearchValue::set(std::vector<value_reg>& value,int32_t maxLength){
    valueAll= value;
    this->maxlength=maxLength;
    this->sum=valueAll.size();
}

void SearchValue::setDefalutType(SearchValueType type){
    defaultType=type;
}

std::vector<value_reg> SearchValue::getValue(){
    return valueAll;
}

size_t SearchValue::getNum(){
    return sum;
}

int32_t SearchValue::getMaxLength(){
    return maxlength;
}