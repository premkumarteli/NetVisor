import { useContext } from 'react';
import { ImmersionContext } from './ImmersionContext';

export const useImmersion = () => {
  const context = useContext(ImmersionContext);
  if (!context) {
    throw new Error('useImmersion must be used within an ImmersionProvider');
  }
  return context;
};
