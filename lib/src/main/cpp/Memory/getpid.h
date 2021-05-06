//
// Created by z742978469 on 20-1-26.
//

#ifndef PEAK_ROOT_SUPPORT_GETPID_H
#define PEAK_ROOT_SUPPORT_GETPID_H

#define GET_PID_LEVEL_EQUAL 1
#define GET_PID_LEVEL_CONTAIN 0


/**
 *
 * @param name : process name
 * @param pids : output
 * @param level : 0>>contain  1>>equal
 * @return
 */
bool getpid(char *name,std::vector<int>& pids,int level);

#endif //PEAK_ROOT_SUPPORT_GETPID_H
